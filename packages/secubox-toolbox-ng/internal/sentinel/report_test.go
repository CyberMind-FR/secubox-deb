// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

import (
	"strings"
	"testing"
)

// TestRenderReportSpywareBlocked asserts a confirmed, neutralized
// commercial-spyware verdict renders a report that names the class, cites the
// matched IOC evidence, states it was neutralized/blocked, carries a
// class-specific mitigation line, and includes ONLY the mac_hash as identity
// (no other PII).
func TestRenderReportSpywareBlocked(t *testing.T) {
	v := Verdict{
		Class:      ClassSpywarePegasus,
		Severity:   95,
		Confidence: 95,
		Action:     ActionBlock,
		Evidence: map[string]string{
			"ioc_type":  "domain",
			"ioc_value": "notif-alert-news.example",
			"source":    "amnesty-mvt",
		},
		MacHash: "abc123devicehash",
		TS:      1_700_000_000,
	}

	report := RenderReport(v)
	lower := strings.ToLower(report)

	// The class must appear.
	if !strings.Contains(report, string(ClassSpywarePegasus)) {
		t.Errorf("report missing class %q:\n%s", ClassSpywarePegasus, report)
	}
	// The matched IOC evidence must appear.
	if !strings.Contains(report, "notif-alert-news.example") {
		t.Errorf("report missing matched IOC evidence:\n%s", report)
	}
	if !strings.Contains(report, "amnesty-mvt") {
		t.Errorf("report missing IOC source evidence:\n%s", report)
	}
	// It was neutralized / blocked.
	if !strings.Contains(lower, "neutralized") || !strings.Contains(lower, "blocked") {
		t.Errorf("report should state the flow was neutralized/blocked:\n%s", report)
	}
	// A spyware-specific mitigation line (isolate device + MVT scan).
	if !strings.Contains(lower, "isolate") || !strings.Contains(lower, "mvt") {
		t.Errorf("report missing spyware mitigation line (isolate/MVT):\n%s", report)
	}
	// mac_hash present …
	if !strings.Contains(report, "abc123devicehash") {
		t.Errorf("report missing mac_hash:\n%s", report)
	}
	// … but no other identity leaked (no raw struct dump / ClientIP field).
	if strings.Contains(report, "ClientIP") {
		t.Errorf("report leaked a non-mac_hash identity field:\n%s", report)
	}
}

// TestRenderReportZeroClickReported asserts a heuristic zero-click verdict
// that was REPORTED (not blocked) renders that disposition explicitly plus
// user-facing advice — never claiming it was blocked.
func TestRenderReportZeroClickReported(t *testing.T) {
	v := Verdict{
		Class:      ClassZeroClick,
		Severity:   65,
		Confidence: 65,
		Action:     ActionReport,
		Evidence: map[string]string{
			"pattern": "one_time_link",
			"url":     "https://x1.notif-push.example/t/ABCDEFGHIJKLMNOP",
		},
		MacHash: "dead00beef11",
		TS:      1_700_000_100,
	}

	report := RenderReport(v)
	lower := strings.ToLower(report)

	if !strings.Contains(report, string(ClassZeroClick)) {
		t.Errorf("report missing class %q:\n%s", ClassZeroClick, report)
	}
	if !strings.Contains(lower, "reported (not blocked)") {
		t.Errorf("report should state 'reported (not blocked)':\n%s", report)
	}
	if !strings.Contains(lower, "advise") {
		t.Errorf("report missing user advice for a zero-click detection:\n%s", report)
	}
	// A report-only verdict must NOT claim it was neutralized/blocked.
	if strings.Contains(lower, "neutralized") {
		t.Errorf("report-only verdict must not claim neutralization:\n%s", report)
	}
}

// TestRenderReportBotnetC2 spot-checks a second block-class mitigation path.
func TestRenderReportBotnetC2(t *testing.T) {
	v := Verdict{
		Class:      ClassBotnetC2,
		Severity:   90,
		Confidence: 90,
		Action:     ActionSinkhole,
		Evidence:   map[string]string{"ioc_type": "domain", "ioc_value": "c2.evil.example"},
		MacHash:    "0011aabb",
	}
	report := RenderReport(v)
	lower := strings.ToLower(report)
	if !strings.Contains(lower, "c2") {
		t.Errorf("botnet report missing C2 mitigation guidance:\n%s", report)
	}
	if !strings.Contains(lower, "neutralized") {
		t.Errorf("sinkhole action should read as neutralized:\n%s", report)
	}
}
