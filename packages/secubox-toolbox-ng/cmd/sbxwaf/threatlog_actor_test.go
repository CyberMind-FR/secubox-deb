// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
)

func TestEntryToEnvelope(t *testing.T) {
	e := &logEntry{
		ClientIP: "203.0.113.7", Host: "nc.gk2.secubox.in", Method: "POST",
		Path: "/files/42?token=x", Category: "sqli", Severity: "high",
		RuleID: "r-001", Action: "banned", UserAgent: "sqlmap/1.7",
		JA4: "ja4-abc", NegativeSpace: "high_value_probe",
	}
	env := entryToEnvelope(e)
	if env.Sensor != envelope.SensorWAF {
		t.Errorf("sensor = %q", env.Sensor)
	}
	if env.Action != envelope.ActionBlock { // banned → block
		t.Errorf("action = %q, attendu block", env.Action)
	}
	if env.Severity != 75 { // high
		t.Errorf("severity = %d, attendu 75", env.Severity)
	}
	if env.PathShape != "/files/:id" { // normalisé, query ignorée
		t.Errorf("path_shape = %q", env.PathShape)
	}
	if env.UserAgentFamily != "sqlmap" {
		t.Errorf("ua_family = %q, attendu sqlmap", env.UserAgentFamily)
	}
	if env.TLSFingerprint != "ja4-abc" {
		t.Errorf("tls_fingerprint = %q", env.TLSFingerprint)
	}
	if env.Vhost != "nc.gk2.secubox.in" {
		t.Errorf("vhost = %q", env.Vhost)
	}
	// Les tags portent catégorie + negative_space.
	tagset := map[string]bool{}
	for _, tg := range env.BehaviorTags {
		tagset[tg] = true
	}
	if !tagset["sqli"] || !tagset["high_value_probe"] {
		t.Errorf("behavior_tags incomplets : %v", env.BehaviorTags)
	}
	// L'enveloppe émise doit être VALIDE (sinon actord la rejetterait).
	if err := env.Validate(); err != nil {
		t.Fatalf("enveloppe émise invalide : %v", err)
	}
}

func TestEntryToEnvelope_ToolPrimeSurUA(t *testing.T) {
	// Un outil déjà identifié prime sur la famille dérivée de l'UA.
	e := &logEntry{ClientIP: "203.0.113.7", Severity: "low", Action: "detect", Tool: "nuclei", UserAgent: "Mozilla/5.0"}
	if got := entryToEnvelope(e).UserAgentFamily; got != "nuclei" {
		t.Errorf("ua_family = %q, attendu nuclei", got)
	}
	// action "detect" → observe (pas block).
	if entryToEnvelope(e).Action != envelope.ActionObserve {
		t.Error("detect devrait mapper vers observe")
	}
}
