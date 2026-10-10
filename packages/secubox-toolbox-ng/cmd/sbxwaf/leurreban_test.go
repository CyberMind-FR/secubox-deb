// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDureeLeurre_GradueeParRecidive(t *testing.T) {
	for r, want := range map[int]time.Duration{0: time.Hour, 1: 24 * time.Hour, 2: 7 * 24 * time.Hour, 9: 7 * 24 * time.Hour} {
		if got := dureeLeurre(r); got != want {
			t.Fatalf("dureeLeurre(%d) = %s, attendu %s", r, got, want)
		}
	}
}

func demandeLeurre(host, remote string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://x/.env", nil)
	req.Host = host
	req.RemoteAddr = remote
	return req
}

// attend que la goroutine de ban ait posé la commande attendue.
func attendNft(fx *fauxNft, motif string) bool {
	fin := time.Now().Add(2 * time.Second)
	for time.Now().Before(fin) {
		if strings.Contains(joint(fx.dernier()), motif) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func TestLeurre_PremierHitBannitUneHeure(t *testing.T) {
	srv, logPath, fx := serveurAnomalieNft(t)
	srv.leurreBan = true
	srv.recordHostAnomalyAvecLeurre(demandeLeurre("scan.example.org", "203.0.113.50:4444"), "scan.example.org", "sonde_racine", "alea")
	if data, _ := os.ReadFile(logPath); !strings.Contains(string(data), `"action":"banned"`) {
		t.Fatalf("le hit sur le leurre doit être journalisé banned : %s", data)
	}
	if !attendNft(fx, "203.0.113.50 timeout 3600s") {
		t.Fatalf("ban d'1 h attendu ; dernière commande : %q", joint(fx.dernier()))
	}
}

func TestLeurre_RecidiveBannit24h(t *testing.T) {
	srv, _, fx := serveurAnomalieNft(t)
	srv.leurreBan = true
	_ = srv.nftBan.store.Append(BanRecord{IP: "203.0.113.51", Category: "leurre:unrouted", Severity: "high", At: time.Now().Add(-48 * time.Hour).Unix(), Action: "ban"})
	srv.recordHostAnomalyAvecLeurre(demandeLeurre("scan.example.org", "203.0.113.51:4444"), "scan.example.org", "sonde_racine", "alea")
	if !attendNft(fx, "203.0.113.51 timeout 86400s") {
		t.Fatalf("ban de 24 h attendu à la 2e récidive ; dernière commande : %q", joint(fx.dernier()))
	}
}

func TestLeurre_SansDrapeauRienNeChange(t *testing.T) {
	srv, logPath, fx := serveurAnomalieNft(t) // leurreBan = false
	srv.recordHostAnomalyAvecLeurre(demandeLeurre("scan.example.org", "203.0.113.52:4444"), "scan.example.org", "sonde_racine", "alea")
	if data, _ := os.ReadFile(logPath); strings.Contains(string(data), `"action":"banned"`) {
		t.Fatalf("sans --leurre-ban, un seul hit ne doit pas bannir : %s", data)
	}
	time.Sleep(50 * time.Millisecond)
	if strings.Contains(joint(fx.dernier()), "203.0.113.52") {
		t.Fatalf("aucun ban nft attendu, obtenu %q", joint(fx.dernier()))
	}
}

func TestLeurre_JamaisUnClientLANNiUnHoteDePremierePartie(t *testing.T) {
	srv, _, fx := serveurAnomalieNft(t)
	srv.leurreBan = true
	srv.recordHostAnomalyAvecLeurre(demandeLeurre("scan.example.org", "192.168.1.50:4444"), "scan.example.org", "sonde_racine", "alea")
	srv.widgetHosts = []string{"nextcloud.gk2.secubox.in"}
	srv.recordHostAnomalyAvecLeurre(demandeLeurre("nextcloud.gk2.secubox.in", "203.0.113.53:4444"), "nextcloud.gk2.secubox.in", "sonde_racine", "alea")
	time.Sleep(50 * time.Millisecond)
	for _, ip := range []string{"192.168.1.50", "203.0.113.53"} {
		if strings.Contains(joint(fx.dernier()), ip) {
			t.Fatalf("%s ne doit jamais être banni par le leurre : %q", ip, joint(fx.dernier()))
		}
	}
}
