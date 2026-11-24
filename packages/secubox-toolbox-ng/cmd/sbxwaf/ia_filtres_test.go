// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Seuil et durée de ban par catégorie escalate (#3732).

func regleEscalate(extra string) string {
	return `{"ia_test":{"name":"IA","severity":"high","mode":"escalate"` + extra + `,
		"patterns":[{"id":"f5-1","pattern":"/mgmt/tm/util/bash","desc":"F5"}]}}`
}

// serveurEscalate monte un serveur dont le banneur nft est factice.
func serveurEscalate(t *testing.T, extra string) (http.Handler, *fauxNft, *Server) {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)
	s := newDetectTestServer(t, backend.URL, writeRulesFile(t, regleEscalate(extra)))
	s.escalateBan = NewBan(24*time.Hour, 3)
	fx := &fauxNft{}
	b := banneurTest(t, fx)
	if err := b.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	s.nftBan = b
	return s.handler(), fx, s
}

// ajoutsNft attend (brièvement) que les bans, posés en goroutine, arrivent.
func ajoutsNft(fx *fauxNft, attendu int) []string {
	var out []string
	for i := 0; i < 50; i++ {
		out = nil
		fx.mu.Lock()
		for _, c := range fx.cmds {
			if j := joint(c); strings.Contains(j, "create element") {
				out = append(out, j)
			}
		}
		fx.mu.Unlock()
		if len(out) >= attendu {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	return out
}

func TestEscalate_SeuilParCategorie(t *testing.T) {
	h, fx, _ := serveurEscalate(t, `,"ban_seuil":1`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, detectTestReq("203.0.113.80"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("1er hit : %d, attendu 403 (ban)", rec.Code)
	}
	if n := len(ajoutsNft(fx, 1)); n != 1 {
		t.Fatalf("banneur appelé %d fois, attendu 1", n)
	}
}

func TestEscalate_DureeParCategorie(t *testing.T) {
	h, fx, _ := serveurEscalate(t, `,"ban_seuil":1,"ban_duree":"168h"`)
	h.ServeHTTP(httptest.NewRecorder(), detectTestReq("203.0.113.81"))
	a := ajoutsNft(fx, 1)
	if len(a) != 1 || !strings.Contains(a[0], "timeout 604800s") {
		t.Fatalf("durée attendue 168h (604800s), obtenu %v", a)
	}

	// Sans le champ : durée globale du banneur (1h dans banneurTest).
	h, fx, _ = serveurEscalate(t, `,"ban_seuil":1`)
	h.ServeHTTP(httptest.NewRecorder(), detectTestReq("203.0.113.82"))
	a = ajoutsNft(fx, 1)
	if len(a) != 1 || !strings.Contains(a[0], "timeout 3600s") {
		t.Fatalf("durée globale attendue (3600s), obtenu %v", a)
	}
}

func TestEscalate_ValeursHorsBornesIgnorees(t *testing.T) {
	for _, extra := range []string{
		`,"ban_seuil":0`, `,"ban_seuil":50`, `,"ban_duree":"9000h"`,
		`,"ban_duree":"illisible"`, `,"ban_seuil":"x"`, `,"ban_duree":"30m"`,
	} {
		var journal bytes.Buffer
		log.SetOutput(&journal)
		h, fx, _ := serveurEscalate(t, extra)
		log.SetOutput(os.Stderr)
		if !strings.Contains(journal.String(), "ban_") {
			t.Errorf("%s : pas d'avertissement dans le journal %q", extra, journal.String())
		}
		// Valeurs par défaut : seuil 3, donc le 1er hit passe.
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, detectTestReq("203.0.113.83"))
		if rec.Code == http.StatusForbidden {
			t.Errorf("%s : 1er hit banni, le seuil par défaut (3) doit s'appliquer", extra)
		}
		for i := 0; i < 2; i++ {
			h.ServeHTTP(httptest.NewRecorder(), detectTestReq("203.0.113.83"))
		}
		a := ajoutsNft(fx, 1)
		if len(a) != 1 || !strings.Contains(a[0], "timeout 3600s") {
			t.Errorf("%s : durée globale attendue, obtenu %v", extra, a)
		}
	}
}

func TestEscalate_SansChampsInchange(t *testing.T) {
	h, _, s := serveurEscalate(t, ``)
	for i := 1; i <= 2; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, detectTestReq("203.0.113.84"))
		if rec.Code == http.StatusForbidden {
			t.Fatalf("hit %d : 403, observation attendue avant le seuil 3", i)
		}
	}
	if s.escalateBan.Count("203.0.113.84") != 2 {
		t.Fatal("le compteur partagé n'a pas compté")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, detectTestReq("203.0.113.84"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("3e hit : %d, attendu 403", rec.Code)
	}
}

// Bout en bout (#3732) : catégories EXACTEMENT telles que `secubox-cvectl filtres-ia appliquer` les écrit
// (sortie réelle de filtres_ia.appliquer_filtres, copiée telle quelle), passées au vrai moteur et au vrai
// chemin escalate. Garde le contrat du texte comparé (chemin, ESPACE, requête sans « ? », corps, UA).
const filtresIAFixture = `{"ia_filtres_critique": {"name": "Filtres de l'IA — critique (generated)", "severity": "critical", "mode": "escalate", "generated": true, "ban_seuil": 1, "ban_duree": "168h", "patterns": [{"id": "ia-crit", "pattern": "(?:^[/.]*|/\\.\\.)/x/yyyyyyyy(?:$|[\\s?#])", "desc": "fortiweb CVE-2024-1234 (autre)", "cve": "CVE-2024-1234", "version": 1, "famille": "autre", "produit": "fortiweb", "motif_type": "chemin_exact", "source": "ia"}]}, "ia_filtres_haute": {"name": "Filtres de l'IA — haute (generated)", "severity": "high", "mode": "escalate", "generated": true, "ban_seuil": 1, "ban_duree": "24h", "patterns": [{"id": "ia-haute", "pattern": "(?:^|[\\s&?])action=exec_cmd", "desc": "fortiweb CVE-2024-2222 (autre)", "cve": "CVE-2024-2222", "version": 1, "famille": "autre", "produit": "fortiweb", "motif_type": "parametre_egal", "source": "ia"}]}, "ia_filtres_moyenne": {"name": "Filtres de l'IA — moyenne (generated)", "severity": "medium", "mode": "escalate", "generated": true, "ban_seuil": 3, "ban_duree": "4h", "patterns": [{"id": "ia-moy", "pattern": "foo[ +]barbazqux", "desc": "zzprod CVE-2024-3333 (autre)", "cve": "CVE-2024-3333", "version": 1, "famille": "autre", "produit": "zzprod", "motif_type": "corps_contient", "source": "ia"}]}}`

func TestFiltresIA_FixtureCvectl_Match(t *testing.T) {
	r := LoadRules(writeRulesFile(t, filtresIAFixture))
	cas := []struct {
		chemin, requete, corps string
		touche                 bool
		id                     string
	}{
		{"/x/yyyyyyyy", "", "", true, "ia-crit"},
		{"/x/yyyyyyyy", "a=1", "", true, "ia-crit"},
		{"/x/yyyyyyyyz", "", "", false, ""},
		{"/index.php", "action=exec_cmd", "", true, "ia-haute"},
		{"/index.php", "b=1&action=exec_cmd", "", true, "ia-haute"},
		{"/index.php", "xaction=exec_cmd", "", false, ""},
		{"/p", "", "foo+barbazqux", true, "ia-moy"},
	}
	for _, c := range cas {
		_, _, _, id, hit := r.MatchDetail("GET", c.chemin, c.requete, c.corps, "curl/8", true, nil)
		if hit != c.touche || id != c.id {
			t.Errorf("%s?%s [%s] : hit=%v id=%q, attendu %v %q", c.chemin, c.requete, c.corps, hit, id, c.touche, c.id)
		}
	}
}

func TestFiltresIA_FixtureCvectl_BanAuPremierHit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)
	s := newDetectTestServer(t, backend.URL, writeRulesFile(t, filtresIAFixture))
	s.escalateBan = NewBan(24*time.Hour, 3)
	fx := &fauxNft{}
	b := banneurTest(t, fx)
	if err := b.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	s.nftBan = b
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/x/yyyyyyyy?a=1", nil)
	req.Host = "app.example.com"
	req.RemoteAddr = "203.0.113.90:12345"
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("1er hit ia_filtres_critique : %d, attendu 403 (ban_seuil 1)", rec.Code)
	}
	if a := ajoutsNft(fx, 1); len(a) != 1 || !strings.Contains(a[0], "timeout 604800s") {
		t.Fatalf("ban attendu de 168h (604800s), obtenu %v", a)
	}
}
