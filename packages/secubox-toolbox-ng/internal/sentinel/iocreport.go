// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

// IOCReporter is the async daemon's REPORT-ONLY correlator for the
// non-spyware IOC classes (botnet_c2 / malware / trojan / phishing …) that the
// live threat feeds materialise into the overlay pack. The narrower Spyware
// analyzer only surfaces the commercial-spyware classes, so without this a
// device contacting a known abuse.ch / ThreatFox C2 would be recorded by
// nothing. IOCReporter matches the same IOCSet the inline gate uses, but —
// because the daemon only ever OBSERVES mirrored flows, it never blocks — it
// forces every verdict to ActionReport. So a feed IOC declared `action:block`
// surfaces honestly as "detected / observed", never as "blocked" (the inline
// gate does the blocking, when enabled; the daemon does not).
//
// It deliberately SKIPS the spyware classes (spywareClasses) so it never
// double-reports a hit the Spyware analyzer already emits for the same flow.

import (
	"log"
)

// IOCReporter implements the daemon Analyzer interface over a pack Loader.
// It holds no state beyond the Loader (which owns the hot-reloaded IOC set).
type IOCReporter struct {
	loader *Loader
}

// NewIOCReporter returns a report-only correlator over l's current IOC set.
func NewIOCReporter(l *Loader) *IOCReporter { return &IOCReporter{loader: l} }

// Analyze matches m against every IOC field and emits a report-only verdict for
// each hit whose class is NOT a spyware class (those belong to the Spyware
// analyzer). Fail-open: any panic recovers to no verdicts; a nil loader is a
// no-op. Never blocks.
func (r *IOCReporter) Analyze(m MirrorMsg) (verdicts []*Verdict) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("sentinel: iocreport analyze recovered from panic (fail-open): %v", rec)
			verdicts = nil
		}
	}()

	if r == nil || r.loader == nil {
		return nil
	}

	r.loader.MaybeReload()
	set := r.loader.Set()

	var hits []*IOC
	if ioc, ok := set.MatchDomain(m.Meta.Host); ok && !spywareClasses[ioc.Class] {
		hits = append(hits, ioc)
	}
	if ioc, ok := set.MatchIP(m.Meta.Host); ok && !spywareClasses[ioc.Class] {
		hits = append(hits, ioc)
	}
	if ioc, ok := set.MatchJA3(m.Meta.JA3); ok && !spywareClasses[ioc.Class] {
		hits = append(hits, ioc)
	}
	if ioc, ok := set.MatchJA4(m.Meta.JA4); ok && !spywareClasses[ioc.Class] {
		hits = append(hits, ioc)
	}
	if ioc, ok := set.MatchCertSHA1(m.Meta.CertSHA1); ok && !spywareClasses[ioc.Class] {
		hits = append(hits, ioc)
	}
	if ioc, ok := set.MatchURL(m.Meta.URL); ok && !spywareClasses[ioc.Class] {
		hits = append(hits, ioc)
	}

	if len(hits) == 0 {
		return nil
	}

	verdicts = make([]*Verdict, 0, len(hits))
	for _, ioc := range hits {
		verdicts = append(verdicts, iocReportVerdict(ioc, m))
	}
	return verdicts
}

// iocReportVerdict builds a REPORT-ONLY verdict for a non-spyware IOC hit. The
// action is ALWAYS ActionReport regardless of the IOC's declared action: the
// async daemon observes, it does not block, so surfacing "blocked" would
// over-claim. `disposition:observed` makes that explicit for the reporter.
func iocReportVerdict(ioc *IOC, m MirrorMsg) *Verdict {
	return &Verdict{
		Class:      ioc.Class,
		Severity:   ioc.Severity,
		Confidence: ioc.Severity,
		Action:     ActionReport, // daemon observes only — never block
		Evidence: map[string]string{
			"ioc_type":    string(ioc.Type),
			"ioc_value":   ioc.Value,
			"source":      ioc.Source,
			"disposition": "observed",
		},
		MacHash: m.Meta.MacHash,
		TS:      m.TS,
	}
}
