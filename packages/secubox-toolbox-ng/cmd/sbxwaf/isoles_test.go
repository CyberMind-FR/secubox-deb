// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
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

const isolesJSON = `{"genere_le": 1800000000, "isoles": [
 {"ip": "192.168.1.20", "nom": "TV <salon>", "depuis": 1800000000, "motif": "infection : <b>c2</b> & co"},
 {"ip": "fd00:0::20", "nom": "TV", "depuis": 1800000000, "motif": "infection"}]}`

func serveurIsoles(t *testing.T, contenu *string) *Server {
	t.Helper()
	chemin := filepath.Join(t.TempDir(), "garde-isoles.json")
	if contenu != nil {
		if err := os.WriteFile(chemin, []byte(*contenu), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &Server{
		routeLookup: func(string) (string, int, bool) { return "", 0, false },
		isoles:      NewListeIsoles(chemin),
	}
}

func TestIsolesPageOuQuatreCentVingtEtUn(t *testing.T) {
	valide, invalide, vide := isolesJSON, "{pas du json", `{"isoles": []}`
	cas := []struct {
		nom     string
		contenu *string
		remote  string
		veut    int
	}{
		{"isolée v4", &valide, "192.168.1.20:5555", http.StatusOK},
		{"isolée v6 forme normalisée", &valide, "[fd00::20]:5555", http.StatusOK},
		{"non isolée", &valide, "192.168.1.21:5555", http.StatusMisdirectedRequest},
		{"fichier absent", nil, "192.168.1.20:5555", http.StatusMisdirectedRequest},
		{"fichier invalide", &invalide, "192.168.1.20:5555", http.StatusMisdirectedRequest},
		{"liste vide", &vide, "192.168.1.20:5555", http.StatusMisdirectedRequest},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			srv := serveurIsoles(t, c.contenu)
			req := httptest.NewRequest(http.MethodGet, "http://inconnu.example/", nil)
			req.Host = "inconnu.example"
			req.RemoteAddr = c.remote
			rec := httptest.NewRecorder()
			srv.handler().ServeHTTP(rec, req)
			if rec.Code != c.veut {
				t.Fatalf("code %d, veut %d", rec.Code, c.veut)
			}
			if c.veut == http.StatusOK {
				if rec.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("Cache-Control no-store attendu")
				}
				if !strings.HasPrefix(rec.Header().Get("Content-Security-Policy"), "default-src 'none'; style-src 'sha256-") {
					t.Fatalf("CSP inattendue %q", rec.Header().Get("Content-Security-Policy"))
				}
				if !strings.Contains(rec.Body.String(), "Cet appareil est isolé") {
					t.Fatal("page d'explication attendue")
				}
			}
		})
	}
}

func TestIsolesRouteNonTouchee(t *testing.T) {
	valide := isolesJSON
	srv := serveurIsoles(t, &valide)
	if _, ok := srv.isoles.Cherche("192.168.1.20"); !ok {
		t.Fatal("adresse attendue isolée")
	}
	// L'insertion est dans la seule branche non routée : un hôte routé ne la lit pas.
	srv.routeLookup = func(string) (string, int, bool) { return "127.0.0.1", 1, true }
	srv.upstreamTimeout = 200 * time.Millisecond
	req := httptest.NewRequest(http.MethodGet, "http://route.example/", nil)
	req.Host = "route.example"
	req.RemoteAddr = "192.168.1.20:5555"
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "Cet appareil est isolé") {
		t.Fatal("un hôte routé ne doit jamais recevoir la page d'isolement")
	}
}

func TestIsolesEchappement(t *testing.T) {
	rec := httptest.NewRecorder()
	writeIsole(rec, isoleEntree{Nom: "<script>x</script>", Motif: `"><img src=x>`, Depuis: 1800000000})
	b := rec.Body.String()
	if strings.Contains(b, "<script>x") || strings.Contains(b, "<img") {
		t.Fatal("valeurs non échappées")
	}
	if !strings.Contains(b, "&lt;script&gt;x") || !strings.Contains(b, "&#34;&gt;&lt;img") {
		t.Fatalf("échappement attendu : %s", b)
	}
}

func TestIsolesRelectureSurChangement(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "garde-isoles.json")
	horloge := time.Unix(1800000000, 0)
	l := NewListeIsoles(chemin)
	l.now = func() time.Time { return horloge }
	if _, ok := l.Cherche("192.168.1.20"); ok {
		t.Fatal("fichier absent : rien d'isolé")
	}
	if err := os.WriteFile(chemin, []byte(isolesJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Cherche("192.168.1.20"); ok {
		t.Fatal("moins d'une seconde : pas de nouveau stat")
	}
	horloge = horloge.Add(2 * time.Second)
	if e, ok := l.Cherche("192.168.1.20"); !ok || e.Nom != "TV <salon>" {
		t.Fatal("relecture attendue après changement")
	}
	if err := os.WriteFile(chemin, []byte(`{"isoles":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(chemin, horloge.Add(time.Minute), horloge.Add(time.Minute))
	horloge = horloge.Add(2 * time.Second)
	if _, ok := l.Cherche("192.168.1.20"); ok {
		t.Fatal("liste vidée : plus isolée")
	}
	_ = os.Remove(chemin)
	horloge = horloge.Add(2 * time.Second)
	if _, ok := l.Cherche("192.168.1.20"); ok {
		t.Fatal("fichier retiré : rien d'isolé")
	}
	var nilListe *ListeIsoles
	if _, ok := nilListe.Cherche("192.168.1.20"); ok {
		t.Fatal("nil-safe")
	}
}
