// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

//go:build cgo && yara

// cgo-backed YARA engine wrapping github.com/hillu/go-yara/v4 (which itself
// wraps libyara via cgo). This file is ONLY built when explicitly requested
// with `-tags yara` AND cgo is enabled — the default build (and the default
// .deb build, per Task 12) uses yara_stub.go instead, so libyara is never a
// hard requirement.
//
// Building this file requires the libyara C library + headers installed
// (Debian/Ubuntu: `apt install libyara-dev`) plus a C toolchain and
// CGO_ENABLED=1, e.g.:
//
//	CGO_ENABLED=1 go build -tags yara ./...
//	CGO_ENABLED=1 go test -tags yara ./internal/sentinel/ -run TestYara
//
// Per the plan's hot-path constraint, this engine is NEVER called from
// sbxmitm's inline gate — it is an Analyzer plugged into the async
// sbx-sentinel daemon (cmd/sbx-sentinel), which mirrors flow bodies off the
// hot path before scanning them.
package sentinel

import (
	"fmt"
	"os"

	yara "github.com/hillu/go-yara/v4"
)

// YaraEngine holds a compiled YARA ruleset (from rulePaths given to
// NewYaraEngine) and scans mirrored flow bodies against it. It implements
// the sbx-sentinel Analyzer interface via Analyze.
type YaraEngine struct {
	rules *yara.Rules
}

// NewYaraEngine compiles the YARA rule files at rulePaths (each added under
// its basename as namespace, to disambiguate identically-named rules across
// files) into a single ruleset. It returns an error if any file fails to
// compile — a bad rule pack must not silently produce an inert engine.
func NewYaraEngine(rulePaths []string) (*YaraEngine, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("sentinel: yara: new compiler: %w", err)
	}

	for _, p := range rulePaths {
		if err := addRuleFile(compiler, p); err != nil {
			return nil, err
		}
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return nil, fmt.Errorf("sentinel: yara: compile rules: %w", err)
	}

	return &YaraEngine{rules: rules}, nil
}

// addRuleFile opens and compiles one rule file into compiler under a
// namespace derived from its path, so identically-named rules in separate
// files don't collide.
func addRuleFile(compiler *yara.Compiler, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("sentinel: yara: open %q: %w", path, err)
	}
	defer f.Close()

	if err := compiler.AddFile(f, path); err != nil {
		return fmt.Errorf("sentinel: yara: compile %q: %w", path, err)
	}
	return nil
}

// Scan runs the compiled ruleset against body and returns the names of all
// matched rules (nil if none matched or the engine has no rules loaded). It
// never panics: a scan error is treated as "no match" (fail-open), since a
// YARA engine failure must never be mistaken for a confirmed clean body by
// its caller escalating it into anything worse than "no verdict".
func (y *YaraEngine) Scan(body []byte) (matches []string) {
	if y == nil || y.rules == nil || len(body) == 0 {
		return nil
	}

	var mr yara.MatchRules
	if err := y.rules.ScanMem(body, 0, 0, &mr); err != nil {
		return nil
	}

	for _, m := range mr {
		matches = append(matches, m.Rule)
	}
	return matches
}

// Analyze implements the sbx-sentinel Analyzer interface: it scans the
// mirrored message body and turns every matched rule name into a Verdict.
// A YARA hit is a high-confidence, known-bad signature match — Class malware,
// strip action. Confidence is set to 90 (>= sentinel.HighConfidenceThreshold),
// so a confirmed rule match survives the daemon's FinalizeAction and actually
// strips rather than being silently downgraded to report-only. A YARA match is
// among the highest-certainty detections in the engine, so it warrants acting.
func (y *YaraEngine) Analyze(m MirrorMsg) []*Verdict {
	names := y.Scan(m.Body)
	if len(names) == 0 {
		return nil
	}

	verdicts := make([]*Verdict, 0, len(names))
	for _, name := range names {
		verdicts = append(verdicts, &Verdict{
			Class:      ClassMalware,
			Severity:   90,
			Confidence: 90,
			Action:     ActionStrip,
			Evidence:   map[string]string{"yara_rule": name},
			MacHash:    m.Meta.MacHash,
			TS:         m.TS,
		})
	}
	return verdicts
}

// Close releases the underlying YARA ruleset.
func (y *YaraEngine) Close() error {
	if y != nil && y.rules != nil {
		y.rules.Destroy()
	}
	return nil
}
