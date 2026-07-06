// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// TestYaraStub carries NO build tag, so it runs on every build configuration
// including the default (no-cgo, no `-tags yara`) build — it is the proof
// that the default build stays functional with YARA simply disabled. The
// real-libyara test below (`//go:build yara`) is the deploy-time variant.
package sentinel

import "testing"

func TestYaraStub(t *testing.T) {
	eng, err := NewYaraEngine(nil)
	if err != nil {
		t.Fatalf("NewYaraEngine(nil) returned error: %v", err)
	}
	if eng == nil {
		t.Fatal("NewYaraEngine(nil) returned a nil engine with no error")
	}

	if got := eng.Scan([]byte("anything")); got != nil {
		t.Fatalf("Scan on stub engine = %v, want nil", got)
	}

	msg := MirrorMsg{Meta: FlowMeta{MacHash: "deadbeef"}, Body: []byte("anything"), TS: 1}
	if got := eng.Analyze(msg); got != nil {
		t.Fatalf("Analyze on stub engine = %v, want nil", got)
	}

	if err := eng.Close(); err != nil {
		t.Fatalf("Close on stub engine returned error: %v", err)
	}
}
