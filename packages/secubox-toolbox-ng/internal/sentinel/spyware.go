// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Commercial-spyware indicator engine: the async Analyzer that correlates a
// mirrored flow's observable metadata (host, URL, JA3/JA4, cert SHA1)
// against the SPYWARE-class IOCs (Pegasus/Predator/Intellexa known-infra,
// plus the zero-click delivery-URL heuristic class) in the currently loaded
// pack set. It is deliberately narrower than the inline Gate (Task 3), which
// matches every class on the hot path: Spyware only reports on — and only
// ever acts on — the commercial-spyware-relevant subset, so its verdicts can
// carry spyware-specific evidence/handling without affecting the generic
// gate's behavior for malware/botnet/phishing IOCs.
//
// Per the plan's Global Constraints (block vs report split): a confirmed
// known-infra hit (ClassSpywarePegasus/Predator/Intellexa) carries the IOC's
// declared action at high confidence (>= HighConfidenceThreshold) so it
// survives FinalizeAction and can neutralize. A ClassZeroClick hit — a
// heuristic delivery-URL SHAPE match, not a confirmed compromise — is always
// forced to ActionReport here, regardless of what the matched IOC declared,
// as defense in depth on top of the base pack's own report-only content
// invariant (TestBasePackZeroClickIsReportOnly) and scorer.go's
// FinalizeAction downgrade: a heuristic verdict must never auto-block no
// matter how many layers would have had to fail for that to happen.
package sentinel

import "log"

// spywareClasses is the set of ThreatClass values Spyware.Analyze reports
// on. A matched IOC belonging to any other class (malware, botnet_c2,
// phishing, ...) is left to the inline gate / other analyzers and produces
// no verdict here.
var spywareClasses = map[ThreatClass]bool{
	ClassSpywarePegasus:   true,
	ClassSpywarePredator:  true,
	ClassSpywareIntellexa: true,
	ClassZeroClick:        true,
}

// Spyware implements the sbx-sentinel Analyzer interface (Analyze). It holds
// no state of its own beyond the Loader it reads the current IOC set from —
// all detection state lives in the pack content, which the Loader keeps
// fresh via MaybeReload. Zero value is not usable; construct with
// NewSpyware. All exported methods are safe for concurrent use (Loader.Set
// is).
type Spyware struct {
	loader *Loader
}

// NewSpyware returns a Spyware backed by l.
func NewSpyware(l *Loader) *Spyware {
	return &Spyware{loader: l}
}

// Analyze implements the Analyzer interface: it checks m's Host, URL, JA3,
// JA4 and CertSHA1 against the loaded IOCSet and returns one Verdict per
// distinct spyware-class match (zero, one, or several — a flow can, for
// instance, match both a known C2 domain and a zero-click delivery URL in
// the same message). It never panics: any failure (including a nil loader)
// is recovered and treated as no verdicts, matching the engine-wide
// fail-open philosophy — a Sentinel bug must degrade to "no detection this
// message", never take the analyzer down.
func (s *Spyware) Analyze(m MirrorMsg) (verdicts []*Verdict) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("sentinel: spyware analyze recovered from panic (fail-open): %v", r)
			verdicts = nil
		}
	}()

	if s == nil || s.loader == nil {
		return nil
	}

	s.loader.MaybeReload()
	set := s.loader.Set()

	var hits []*IOC
	if ioc, ok := set.MatchDomain(m.Meta.Host); ok && spywareClasses[ioc.Class] {
		hits = append(hits, ioc)
	}
	if ioc, ok := set.MatchJA3(m.Meta.JA3); ok && spywareClasses[ioc.Class] {
		hits = append(hits, ioc)
	}
	if ioc, ok := set.MatchJA4(m.Meta.JA4); ok && spywareClasses[ioc.Class] {
		hits = append(hits, ioc)
	}
	if ioc, ok := set.MatchCertSHA1(m.Meta.CertSHA1); ok && spywareClasses[ioc.Class] {
		hits = append(hits, ioc)
	}
	if ioc, ok := set.MatchURL(m.Meta.URL); ok && spywareClasses[ioc.Class] {
		hits = append(hits, ioc)
	}

	if len(hits) == 0 {
		return nil
	}

	verdicts = make([]*Verdict, 0, len(hits))
	for _, ioc := range hits {
		verdicts = append(verdicts, spywareVerdict(ioc, m))
	}
	return verdicts
}

// spywareVerdict builds the Verdict for one matched spyware-class IOC.
//
//   - Known-infra classes (Pegasus/Predator/Intellexa): Confidence is set to
//     the IOC's curated Severity — mirroring the inline Gate's philosophy
//     that a direct indicator hit against curated content is not a
//     probabilistic guess, so severity and confidence coincide. Every
//     known-infra entry the base pack ships has Severity >= 90 (enforced by
//     TestBasePackKnownInfraIsHighSeverity), comfortably above
//     HighConfidenceThreshold (85), so the verdict survives FinalizeAction
//     and Action (the IOC's declared action, e.g. block) is actually applied.
//   - ClassZeroClick (a heuristic class per scorer.go's IsHeuristicClass):
//     Action is forced to ActionReport here regardless of what the matched
//     IOC declared. This does not rely solely on the caller invoking
//     FinalizeAction — it is a second, independent guarantee at the source
//     of the verdict, matching Behavioral's same defense-in-depth choice.
func spywareVerdict(ioc *IOC, m MirrorMsg) *Verdict {
	action := ioc.Action
	if IsHeuristicClass(ioc.Class) {
		action = ActionReport
	}

	return &Verdict{
		Class:      ioc.Class,
		Severity:   ioc.Severity,
		Confidence: ioc.Severity,
		Action:     action,
		Evidence: map[string]string{
			"ioc_type":  string(ioc.Type),
			"ioc_value": ioc.Value,
			"source":    ioc.Source,
		},
		MacHash: m.Meta.MacHash,
		TS:      m.TS,
	}
}
