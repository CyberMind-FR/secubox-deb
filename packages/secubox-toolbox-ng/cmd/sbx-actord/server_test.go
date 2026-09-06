// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/store"
)

func serveur(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "actord.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return &Server{store: st, shadow: true}
}

// bout-en-bout : capteur -> socket d'ingestion -> validation -> store -> /stats.
func TestIngestionBoutEnBout(t *testing.T) {
	s := serveur(t)
	sock := filepath.Join(t.TempDir(), "ingest.sock")
	ch := make(chan *envelope.Envelope, 16)
	go s.worker(ch)
	go func() { _ = s.serveIngest(sock, ch) }()

	// Attendre que le socket écoute.
	var conn net.Conn
	var err error
	for i := 0; i < 100; i++ {
		if conn, err = net.Dial("unix", sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("connexion au socket d'ingestion : %v", err)
	}

	valide := envelope.Envelope{
		EventID: envelope.NewEventID(), Timestamp: time.Now().Unix(),
		Sensor: envelope.SensorWAF, SrcIP: "203.0.113.9",
		Action: envelope.ActionBlock, Severity: 70, PathShape: "/wp-login.php",
	}
	blob, _ := json.Marshal(valide)
	if _, err := conn.Write(append(blob, '\n')); err != nil {
		t.Fatal(err)
	}
	// Un événement forgé (sensor inconnu) doit être compté "invalid", pas ingéré.
	if _, err := conn.Write([]byte(`{"sensor":"martien","src_ip":"1.2.3.4","timestamp":1788000000}` + "\n")); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	// Ingestion asynchrone : on attend le drainage.
	deadline := time.Now().Add(3 * time.Second)
	for s.ingested.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := s.ingested.Load(); got != 1 {
		t.Fatalf("ingested = %d, attendu 1", got)
	}
	if got := s.invalid.Load(); got != 1 {
		t.Fatalf("invalid = %d, attendu 1 (événement forgé)", got)
	}

	// L'API /stats reflète l'événement (contrat consommé par la console).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/actor/stats", nil)
	w := httptest.NewRecorder()
	s.handleStats(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("stats HTTP %d", w.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["events_24h"].(float64) != 1 {
		t.Errorf("events_24h = %v, attendu 1", out["events_24h"])
	}
	if out["blocked_24h"].(float64) != 1 {
		t.Errorf("blocked_24h = %v, attendu 1", out["blocked_24h"])
	}
	if out["mode"] != "observe" || out["shadow"] != true {
		t.Errorf("mode/shadow inattendus : %v / %v", out["mode"], out["shadow"])
	}
	// Aucun acteur inventé tant que le graphe n'est pas branché.
	if out["actors"].(float64) != 0 {
		t.Errorf("actors = %v, attendu 0 (pas de corrélation en Phase 0)", out["actors"])
	}
}
