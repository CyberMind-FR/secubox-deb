// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

//go:build !yara

// No-cgo YARA stub: this is what ships in the DEFAULT build (and the
// standard .deb build unless explicitly built with `-tags yara` against an
// installed libyara-dev — see yara.go). It keeps the sentinel package
// cgo-free and dependency-free by construction: NewYaraEngine always
// succeeds, Scan is always a no-op (nil, meaning "no match"), and Analyze
// never produces verdicts. This lets sbx-sentinel/sbxmitm wire a YaraEngine
// unconditionally without caring whether YARA support was compiled in.
package sentinel

// YaraEngine is the no-op stand-in for the cgo-backed YARA engine (yara.go,
// build tag `cgo && yara`). rulePaths passed to NewYaraEngine are accepted
// but ignored — there is nothing to compile without libyara.
type YaraEngine struct{}

// NewYaraEngine always succeeds in the stub build: YARA is simply disabled,
// never an error condition (fail-open — Task brief: the default build must
// compile and run with YARA disabled).
func NewYaraEngine(rulePaths []string) (*YaraEngine, error) {
	return &YaraEngine{}, nil
}

// Scan always returns nil (no matches) in the stub build.
func (y *YaraEngine) Scan(body []byte) []string {
	return nil
}

// Analyze always returns nil (no verdicts) in the stub build.
func (y *YaraEngine) Analyze(m MirrorMsg) []*Verdict {
	return nil
}

// Close is a no-op in the stub build.
func (y *YaraEngine) Close() error {
	return nil
}
