// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

//go:build yara

// Real-libyara exercise of YaraEngine. Split into its own file (rather than
// living alongside TestYaraStub in yara_test.go) because Go build
// constraints are file-scoped: TestYaraStub must run untagged on the
// default build, while this test only makes sense — and only compiles —
// against the cgo-backed engine in yara.go, so it carries the `yara` tag
// exclusively. Run with: CGO_ENABLED=1 go test -tags yara ./internal/sentinel/ -run TestYara
package sentinel

import (
	"os"
	"path/filepath"
	"testing"
)

func TestYaraRealEngineMatchesRule(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "eicar.yar")
	rule := "rule t { strings: $a = \"EICAR-STANDARD\" condition: $a }\n"
	if err := os.WriteFile(rulePath, []byte(rule), 0o644); err != nil {
		t.Fatalf("write rule file: %v", err)
	}

	eng, err := NewYaraEngine([]string{rulePath})
	if err != nil {
		t.Fatalf("NewYaraEngine: %v", err)
	}
	defer eng.Close()

	matches := eng.Scan([]byte("this body contains EICAR-STANDARD marker"))
	if len(matches) != 1 || matches[0] != "t" {
		t.Fatalf("Scan(infected) = %v, want [\"t\"]", matches)
	}

	if clean := eng.Scan([]byte("this body is perfectly clean")); clean != nil {
		t.Fatalf("Scan(clean) = %v, want nil", clean)
	}
}
