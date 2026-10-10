// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// ── #2240 : un leurre n'a AUCUN autre but que détecter ; tout contact avec lui est banni, partout ───────────────────────────────────────────
func TestBanLeurre_PlagesProtegeesJamaisBannies(t *testing.T) {
	srv, _, fx := serveurAnomalieNft(t)
	srv.leurreBan = true
	srv.protegees = parseCIDRs("203.0.113.0/24")
	srv.banLeurre("203.0.113.77", "bait", "high", 0) // la box, la Freebox, le maillage : jamais
	srv.banLeurre("198.51.100.7", "bait", "high", 0)
	if !attendNft(fx, "198.51.100.7 timeout 3600s") {
		t.Fatalf("une adresse ordinaire est bannie 1 h : %q", joint(fx.dernier()))
	}
	for _, c := range fx.cmds {
		if strings.Contains(joint(c), "203.0.113.77") {
			t.Fatalf("une adresse protégée ne doit jamais être bannie : %q", joint(c))
		}
	}
}

func TestBanLeurre_MarqueRevenueAuMoinsVingtQuatreHeures(t *testing.T) {
	srv, _, fx := serveurAnomalieNft(t)
	srv.leurreBan = true
	srv.banLeurre("198.51.100.8", "marque-revenue", "high", 24*time.Hour)
	if !attendNft(fx, "198.51.100.8 timeout 86400s") {
		t.Fatalf("une marque rejouée prouve qu'on a moissonné le leurre : 24 h minimum, obtenu %q", joint(fx.dernier()))
	}
}

func TestBanLeurre_SansDrapeauNeFaitRien(t *testing.T) {
	srv, _, fx := serveurAnomalieNft(t) // leurreBan = false
	srv.banLeurre("198.51.100.9", "bait", "high", 0)
	time.Sleep(50 * time.Millisecond)
	if strings.Contains(joint(fx.dernier()), "198.51.100.9") {
		t.Fatalf("sans --leurre-ban rien n'est banni : %q", joint(fx.dernier()))
	}
}

func reponse404Appat(path, remote string) *http.Response {
	req := httptest.NewRequest(http.MethodGet, "http://nc.gk2.secubox.in"+path, nil)
	req.RemoteAddr = remote
	return &http.Response{StatusCode: http.StatusNotFound, Request: req, Header: http.Header{}, Body: http.NoBody}
}

func TestChemin_AppatSurVraiVhost_DeclencheLeBan(t *testing.T) {
	var touches []string
	l := NewLeurreHTTP(true, nil, nil)
	l.surTouche = func(ip string, f familleSonde) { touches = append(touches, ip) }
	if !l.LeurrerLe404(reponse404Appat("/.env", "198.51.100.20:5555")) {
		t.Fatal("un appât intrinsèque est leurré")
	}
	if len(touches) != 1 || touches[0] != "198.51.100.20" {
		t.Fatalf("le contact avec l'appât est signalé pour ban : %v", touches)
	}
}

func TestChemin_NormalOuLAN_NeDeclenchePas(t *testing.T) {
	var touches []string
	l := NewLeurreHTTP(true, nil, nil)
	l.surTouche = func(ip string, f familleSonde) { touches = append(touches, ip) }
	l.LeurrerLe404(reponse404Appat("/page-qui-n-existe-plus", "198.51.100.21:1")) // 404 banale : pas un appât
	l.LeurrerLe404(reponse404Appat("/.env", "192.168.1.50:1"))                    // le LAN n'est jamais leurré
	if len(touches) != 0 {
		t.Fatalf("ni 404 banale ni LAN : %v", touches)
	}
}

func TestMarqueRevenueSurUnVraiService_BanneDansLeHandler(t *testing.T) {
	srv, _, fx := serveurAnomalieNft(t)
	srv.leurreBan = true
	fil := NewFiligrane(secretFiligraneDeTest(t))
	if fil == nil {
		t.Skip("filigrane indisponible dans cet environnement de test")
	}
	srv.leurre = NewLeurreHTTP(true, fil, nil)
	jeton, _ := fil.Marque()
	req := httptest.NewRequest(http.MethodGet, "http://nc.gk2.secubox.in/login?token="+jeton, nil)
	req.RemoteAddr = "198.51.100.30:4444"
	srv.surMarqueRevenue(req)
	if !attendNft(fx, "198.51.100.30 timeout 86400s") {
		t.Fatalf("une marque rejouée sur un service réel est bannie 24 h : %q", joint(fx.dernier()))
	}
}

func secretFiligraneDeTest(t *testing.T) string {
	t.Helper()
	chemin := filepath.Join(t.TempDir(), "filigrane")
	if err := os.WriteFile(chemin, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	return chemin
}
