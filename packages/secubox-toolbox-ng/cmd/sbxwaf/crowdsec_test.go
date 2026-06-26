// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf :: crowdsec_test — CrowdSec LAPI bridge tests

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestCrowdSecAlertPayload verifies that Report POSTs to /v1/alerts with the
// correct Authorization header and a well-formed alert JSON array.
func TestCrowdSecAlertPayload(t *testing.T) {
	type capturedReq struct {
		method string
		path   string
		auth   string
		body   []byte
	}

	var captured capturedReq

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		captured.auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		captured.body = b
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := NewCrowdSecClient(srv.URL, "testjwt", "4h")
	c.Report("1.2.3.4", "sqli", "high")

	// Report is synchronous inside this test (no goroutine wrapper here).
	// Give a tiny window just in case the httptest server needs to flush.
	time.Sleep(20 * time.Millisecond)

	// Method and path.
	if captured.method != http.MethodPost {
		t.Errorf("method: want POST, got %s", captured.method)
	}
	if captured.path != "/v1/alerts" {
		t.Errorf("path: want /v1/alerts, got %s", captured.path)
	}

	// Authorization header.
	if captured.auth != "Bearer testjwt" {
		t.Errorf("Authorization: want 'Bearer testjwt', got %q", captured.auth)
	}

	// Parse the JSON body.
	var alerts []map[string]interface{}
	if err := json.Unmarshal(captured.body, &alerts); err != nil {
		t.Fatalf("body is not valid JSON: %v\nbody: %s", err, captured.body)
	}
	if len(alerts) != 1 {
		t.Fatalf("want 1 alert in array, got %d", len(alerts))
	}
	a := alerts[0]

	// Scenario.
	if got, _ := a["scenario"].(string); got != "secubox-waf/sqli" {
		t.Errorf("scenario: want 'secubox-waf/sqli', got %q", got)
	}

	// Source.
	src, ok := a["source"].(map[string]interface{})
	if !ok {
		t.Fatalf("source field missing or wrong type")
	}
	if v, _ := src["value"].(string); v != "1.2.3.4" {
		t.Errorf("source.value: want '1.2.3.4', got %q", v)
	}
	if v, _ := src["ip"].(string); v != "1.2.3.4" {
		t.Errorf("source.ip: want '1.2.3.4', got %q", v)
	}
	if v, _ := src["scope"].(string); v != "Ip" {
		t.Errorf("source.scope: want 'Ip', got %q", v)
	}

	// Decisions.
	decisionsRaw, ok := a["decisions"].([]interface{})
	if !ok || len(decisionsRaw) != 1 {
		t.Fatalf("decisions: want array of 1, got %v", a["decisions"])
	}
	d, _ := decisionsRaw[0].(map[string]interface{})
	if v, _ := d["type"].(string); v != "ban" {
		t.Errorf("decisions[0].type: want 'ban', got %q", v)
	}
	if v, _ := d["value"].(string); v != "1.2.3.4" {
		t.Errorf("decisions[0].value: want '1.2.3.4', got %q", v)
	}
	if v, _ := d["duration"].(string); v != "4h" {
		t.Errorf("decisions[0].duration: want '4h', got %q", v)
	}
	if v, _ := d["scope"].(string); v != "Ip" {
		t.Errorf("decisions[0].scope: want 'Ip', got %q", v)
	}
	if v, _ := d["origin"].(string); v != "secubox-waf" {
		t.Errorf("decisions[0].origin: want 'secubox-waf', got %q", v)
	}

	// Timestamps: assert fields exist and parse as RFC3339.
	for _, field := range []string{"start_at", "stop_at"} {
		v, _ := a[field].(string)
		if v == "" {
			t.Errorf("%s: field missing or empty", field)
			continue
		}
		if _, err := time.Parse(time.RFC3339, strings.TrimSuffix(v, ".000000Z")); err != nil {
			// The Python uses ".000000Z" suffix; try parsing with that pattern too.
			if _, err2 := time.Parse("2006-01-02T15:04:05.000000Z", v); err2 != nil {
				t.Errorf("%s: %q does not parse as RFC3339 or Python variant: %v / %v", field, v, err, err2)
			}
		}
	}

	// Events array.
	eventsRaw, _ := a["events"].([]interface{})
	if len(eventsRaw) < 1 {
		t.Errorf("events: want at least 1 entry, got %d", len(eventsRaw))
	}
}

// TestCrowdSecBestEffortOnError verifies that Report does not panic when the
// LAPI server is unreachable. Best-effort: errors are logged only.
func TestCrowdSecBestEffortOnError(t *testing.T) {
	c := NewCrowdSecClient("http://127.0.0.1:1", "dummy", "4h")
	// Must return without panic.
	c.Report("1.2.3.4", "sqli", "high")
}
