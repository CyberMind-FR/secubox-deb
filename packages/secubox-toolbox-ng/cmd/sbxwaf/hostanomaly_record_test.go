// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// reporterFake enregistre les rapports CrowdSec via un canal (Report est appelé
// dans une goroutine).
type reporterFake struct{ ch chan [3]string }

func (f *reporterFake) Report(ip, cat, sev string) { f.ch <- [3]string{ip, cat, sev} }

func serveurAnomalie(t *testing.T, rep CrowdSecReporter) (*Server, string) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "threats.log")
	return &Server{
		ban:         NewBan(300*time.Second, 3),
		threatLog:   NewThreatLog(logPath),
		crowdsec:    rep,
		hostAnomaly: true,
	}, logPath
}

func TestRecordHostAnomaly_FortDepuisWANBannitEtRapporte(t *testing.T) {
	rep := &reporterFake{ch: make(chan [3]string, 1)}
	srv, logPath := serveurAnomalie(t, rep)

	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.Host = "203.0.113.9"           // le client vise par IP brute → classe forte
	req.RemoteAddr = "203.0.113.42:12345" // WAN (TEST-NET-3)
	srv.recordHostAnomaly(req, "203.0.113.9")

	// Journal (synchrone) : action « banned » dès le premier coup.
	if data, _ := os.ReadFile(logPath); !contains(string(data), `"action":"banned"`) ||
		!contains(string(data), `"category":"host_anomaly:ip_literal"`) {
		t.Fatalf("journal attendu banned+ip_literal, obtenu: %s", data)
	}
	// CrowdSec (async) : rapport reçu.
	select {
	case c := <-rep.ch:
		if c[0] != "203.0.113.42" || c[1] != "host_anomaly:ip_literal" {
			t.Fatalf("rapport CrowdSec inattendu: %v", c)
		}
	case <-time.After(time.Second):
		t.Fatal("aucun rapport CrowdSec pour une anomalie forte WAN")
	}
}

func TestRecordHostAnomaly_ClientLANObserveSansBannir(t *testing.T) {
	rep := &reporterFake{ch: make(chan [3]string, 1)}
	srv, logPath := serveurAnomalie(t, rep)

	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.Host = "10.10.10.10"
	req.RemoteAddr = "192.168.1.50:5555" // LAN → jamais banni
	srv.recordHostAnomaly(req, "10.10.10.10")

	if data, _ := os.ReadFile(logPath); !contains(string(data), `"action":"detect"`) {
		t.Fatalf("client LAN attendu action detect, obtenu: %s", data)
	}
	select {
	case c := <-rep.ch:
		t.Fatalf("client LAN ne doit PAS être rapporté à CrowdSec: %v", c)
	case <-time.After(120 * time.Millisecond):
		// rien reçu : correct
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
