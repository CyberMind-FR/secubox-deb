// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func isolesJSON(genere int64) string {
	return fmt.Sprintf(`{"genere_le": %d, "isoles": [
 {"ip": "192.168.1.20", "nom": "TV <salon>", "depuis": 1800000000, "motif": "infection : <b>c2</b> & co"},
 {"ip": "fd00:0::20", "nom": "TV", "depuis": 1800000000, "motif": "infection"},
 {"ip": "8.8.8.8", "nom": "public", "depuis": 1800000000, "motif": "x"}]}`, genere)
}

// liste de test : le compte de l'exécutant tient lieu de secubox-garde.
func listeTest(chemin string, journal *[]string) *ListeIsoles {
	l := NewListeIsoles(chemin)
	moi := uint32(os.Getuid())
	l.uidGarde = func() (uint32, bool) { return moi, true }
	l.logf = func(f string, a ...any) {
		if journal != nil {
			*journal = append(*journal, fmt.Sprintf(f, a...))
		}
	}
	return l
}

// dossierSur : dossier 0755 du compte courant (TempDir suit l'umask, qui peut le laisser 0777).
func dossierSur(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "garde")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func ecrireListe(t *testing.T, chemin, contenu string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(chemin, []byte(contenu), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(chemin, mode); err != nil {
		t.Fatal(err)
	}
}

func TestIsolesPageOuQuatreCentVingtEtUn(t *testing.T) {
	frais := isolesJSON(time.Now().Unix())
	cas := []struct {
		nom     string
		contenu string // "" = absent
		remote  string
		veut    int
	}{
		{"isolée v4", frais, "192.168.1.20:5555", http.StatusOK},
		{"isolée v6 forme normalisée", frais, "[fd00::20]:5555", http.StatusOK},
		{"non isolée", frais, "192.168.1.21:5555", http.StatusMisdirectedRequest},
		{"adresse publique jamais exemptée", frais, "8.8.8.8:5555", http.StatusMisdirectedRequest},
		{"fichier absent", "", "192.168.1.20:5555", http.StatusMisdirectedRequest},
		{"fichier invalide", "{pas du json", "192.168.1.20:5555", http.StatusMisdirectedRequest},
		{"liste vide", `{"genere_le": 9999999999, "isoles": []}`, "192.168.1.20:5555", http.StatusMisdirectedRequest},
		{"liste périmée", isolesJSON(time.Now().Add(-11 * time.Minute).Unix()), "192.168.1.20:5555", http.StatusMisdirectedRequest},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			chemin := filepath.Join(dossierSur(t), "isoles.json")
			if c.contenu != "" {
				ecrireListe(t, chemin, c.contenu, 0o644)
			}
			var journal []string
			srv := &Server{
				routeLookup: func(string) (string, int, bool) { return "", 0, false },
				isoles:      listeTest(chemin, &journal),
			}
			req := httptest.NewRequest(http.MethodGet, "http://inconnu.example/", nil)
			req.Host = "inconnu.example"
			req.RemoteAddr = c.remote
			rec := httptest.NewRecorder()
			srv.handler().ServeHTTP(rec, req)
			if rec.Code != c.veut {
				t.Fatalf("code %d, veut %d", rec.Code, c.veut)
			}
			if c.veut != http.StatusOK {
				return
			}
			h := rec.Header()
			if h.Get("Cache-Control") != "no-store" || h.Get("Referrer-Policy") != "no-referrer" {
				t.Fatalf("en-têtes inattendus %v", h)
			}
			if !strings.HasPrefix(h.Get("Content-Security-Policy"), "default-src 'none'; style-src 'sha256-") {
				t.Fatalf("CSP inattendue %q", h.Get("Content-Security-Policy"))
			}
			if !strings.Contains(rec.Body.String(), "Cet appareil est isolé") {
				t.Fatal("page d'explication attendue")
			}
			if len(journal) != 1 || !strings.Contains(journal[0], "isolé-servi") {
				t.Fatalf("une ligne isolé-servi attendue : %v", journal)
			}
		})
	}
}

func TestIsolesFichierPasSur(t *testing.T) {
	frais := isolesJSON(time.Now().Unix())
	cas := []struct {
		nom      string
		prepare  func(t *testing.T, dir, chemin string)
		etranger bool
	}{
		{"lien symbolique", func(t *testing.T, dir, chemin string) {
			vrai := filepath.Join(dir, "vrai.json")
			ecrireListe(t, vrai, frais, 0o644)
			if err := os.Symlink(vrai, chemin); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"fichier inscriptible par le groupe", func(t *testing.T, _, chemin string) {
			ecrireListe(t, chemin, frais, 0o664)
		}, false},
		{"fichier inscriptible par tous", func(t *testing.T, _, chemin string) {
			ecrireListe(t, chemin, frais, 0o646)
		}, false},
		{"dossier inscriptible par tous", func(t *testing.T, dir, chemin string) {
			ecrireListe(t, chemin, frais, 0o644)
			if err := os.Chmod(dir, 0o777); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"autre propriétaire", func(t *testing.T, _, chemin string) {
			ecrireListe(t, chemin, frais, 0o644)
		}, true},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			dir := dossierSur(t)
			chemin := filepath.Join(dir, "isoles.json")
			c.prepare(t, dir, chemin)
			var journal []string
			l := listeTest(chemin, &journal)
			if c.etranger {
				l.uidGarde = func() (uint32, bool) { return 4242424, true }
				if os.Getuid() == 0 {
					t.Skip("root est toujours admis")
				}
			}
			if _, ok := l.Cherche("192.168.1.20"); ok {
				t.Fatal("fichier pas sûr : rien ne doit être exempté")
			}
			if len(journal) != 1 {
				t.Fatalf("une ligne de refus attendue : %v", journal)
			}
		})
	}
}

func TestIsolesRouteNonTouchee(t *testing.T) {
	chemin := filepath.Join(dossierSur(t), "isoles.json")
	ecrireListe(t, chemin, isolesJSON(time.Now().Unix()), 0o644)
	srv := &Server{
		routeLookup:     func(string) (string, int, bool) { return "127.0.0.1", 1, true },
		isoles:          listeTest(chemin, nil),
		upstreamTimeout: 200 * time.Millisecond,
	}
	if _, ok := srv.isoles.Cherche("192.168.1.20"); !ok {
		t.Fatal("adresse attendue isolée")
	}
	req := httptest.NewRequest(http.MethodGet, "http://route.example/", nil)
	req.Host = "route.example"
	req.RemoteAddr = "192.168.1.20:5555"
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "Cet appareil est isolé") {
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

func TestIsolesTraceLimitee(t *testing.T) {
	var journal []string
	horloge := time.Unix(1800000000, 0)
	l := listeTest("/inexistant", &journal)
	l.now = func() time.Time { return horloge }
	l.Trace("192.168.1.20", "a.example")
	l.Trace("192.168.1.20", "b.example")
	l.Trace("192.168.1.21", "a.example")
	horloge = horloge.Add(61 * time.Second)
	l.Trace("192.168.1.20", "c.example")
	if len(journal) != 3 {
		t.Fatalf("3 lignes attendues (une par adresse et par minute) : %v", journal)
	}
}

func TestIsolesRelectureSurChangement(t *testing.T) {
	chemin := filepath.Join(dossierSur(t), "isoles.json")
	horloge := time.Now()
	l := listeTest(chemin, nil)
	l.now = func() time.Time { return horloge }
	if _, ok := l.Cherche("192.168.1.20"); ok {
		t.Fatal("fichier absent : rien d'isolé")
	}
	ecrireListe(t, chemin, isolesJSON(horloge.Unix()), 0o644)
	if _, ok := l.Cherche("192.168.1.20"); ok {
		t.Fatal("moins d'une seconde : pas de nouveau stat")
	}
	horloge = horloge.Add(2 * time.Second)
	if e, ok := l.Cherche("192.168.1.20"); !ok || e.Nom != "TV <salon>" {
		t.Fatal("relecture attendue après changement")
	}
	horloge = horloge.Add(isolesPerimee)
	if _, ok := l.Cherche("192.168.1.20"); ok {
		t.Fatal("liste périmée : plus isolée")
	}
	ecrireListe(t, chemin, fmt.Sprintf(`{"genere_le": %d, "isoles":[]}`, horloge.Unix()), 0o644)
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
