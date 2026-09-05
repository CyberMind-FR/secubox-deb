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

// serveurAnomalieNft monte un serveur dont le ban passe par le banneur nft du
// WAF — le seul chemin de blocage depuis #1218.
func serveurAnomalieNft(t *testing.T) (*Server, string, *fauxNft) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "threats.log")
	fx := &fauxNft{}
	nb := NewNftBanner("nft", "secubox", time.Hour,
		NewBanStore(filepath.Join(t.TempDir(), "bans.jsonl")))
	nb.runner = fx.run
	if err := nb.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	return &Server{
		ban:         NewBan(300*time.Second, 3),
		threatLog:   NewThreatLog(logPath),
		hostAnomaly: true,
		nftBan:      nb,
	}, logPath, fx
}

// Une anomalie FORTE venue du WAN doit être bannie par le WAF LUI-MÊME (#1218),
// sans relais : l'adresse doit entrer dans le set nft que la chaîne consulte.
func TestRecordHostAnomaly_FortDepuisWANBannitParLeWAF(t *testing.T) {
	srv, logPath, fx := serveurAnomalieNft(t)

	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.Host = "203.0.113.9"              // le client vise par IP brute → classe forte
	req.RemoteAddr = "203.0.113.42:12345" // WAN (TEST-NET-3)
	srv.recordHostAnomaly(req, "203.0.113.9")

	// Journal (synchrone) : action « banned » dès le premier coup.
	if data, _ := os.ReadFile(logPath); !contains(string(data), `"action":"banned"`) ||
		!contains(string(data), `"category":"host_anomaly:ip_literal"`) {
		t.Fatalf("journal attendu banned+ip_literal, obtenu: %s", data)
	}

	// Le ban nft est posé dans une goroutine : on attend l'élément.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if contains(joint(fx.dernier()), "add element inet secubox waf_ban") &&
			contains(joint(fx.dernier()), "203.0.113.42") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("l'adresse n'a pas été ajoutée au set nft ; dernière commande: %q", joint(fx.dernier()))
}

func TestRecordHostAnomaly_ClientLANObserveSansBannir(t *testing.T) {
	srv, logPath, fx := serveurAnomalieNft(t)

	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.Host = "10.10.10.10"
	req.RemoteAddr = "192.168.1.50:5555" // LAN → jamais banni
	srv.recordHostAnomaly(req, "10.10.10.10")

	if data, _ := os.ReadFile(logPath); !contains(string(data), `"action":"detect"`) {
		t.Fatalf("client LAN attendu action detect, obtenu: %s", data)
	}
	// Un client LAN ne doit JAMAIS entrer dans le set nft (aucun ban posé) :
	// on laisse une éventuelle goroutine de ban s'exécuter, puis on vérifie.
	time.Sleep(150 * time.Millisecond)
	if contains(joint(fx.dernier()), "192.168.1.50") {
		t.Fatalf("client LAN ne doit PAS être banni (nft): %q", joint(fx.dernier()))
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
