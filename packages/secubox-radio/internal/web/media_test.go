package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// avecFichier prepare une piste prete et une passerelle qui rend `contenu`.
//
// LE FLUX EST INJECTE : la radio RELAIE desormais au lieu de recopier, et les
// tests n'ont donc pas besoin d'un fichier sur disque — ils ont besoin d'une
// passerelle, que l'on remplace.
func avecFichier(t *testing.T, s *Serveur, contenu string) int64 {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "audio/ogg")
		http.ServeContent(w, r, "p.ogg", time.Time{}, strings.NewReader(contenu))
	}))
	t.Cleanup(srv.Close)
	s.Flux = func(ctx context.Context, ytID, plage string) (*http.Response, error) {
		req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
		if plage != "" {
			req.Header.Set("Range", plage)
		}
		return http.DefaultClient.Do(req)
	}
	p, _, err := s.st.Ajoute("https://youtu.be/ABC", "T", 1, s.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.st.PoseCache(p.ID, "/data/ytsas/ABC/ABC.mp4", "audio/ogg", 0, 180000, "T", "A"); err != nil {
		t.Fatal(err)
	}
	return p.ID
}

func get(s *Serveur, chemin, qui string, entetes map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", chemin, nil)
	if qui != dehors {
		r.Header.Set("X-Test-Qui", qui)
	}
	for k, v := range entetes {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// ── LA PROPRIETE QUI COMPTE ─────────────────────────────────────────────────
//
// Un auditeur qui rejoint la radio en cours demande « a partir de 3 min 41 ».
// Sans requetes de plage, le navigateur telecharge tout depuis le debut avant
// de pouvoir jouer, et la synchronisation est perdue.
func TestLeMediaRepondAuxRequetesDePlage(t *testing.T) {
	s, _ := banc(t)
	id := avecFichier(t, s, "0123456789abcdef")

	w := get(s, "/media/"+itoa(id), membre, map[string]string{"Range": "bytes=4-9"})
	if w.Code != http.StatusPartialContent {
		t.Fatalf("code %d au lieu de 206 : les plages ne sont pas servies", w.Code)
	}
	if got := w.Body.String(); got != "456789" {
		t.Errorf("corps = %q, attendu %q", got, "456789")
	}
	if cr := w.Header().Get("Content-Range"); cr != "bytes 4-9/16" {
		t.Errorf("Content-Range = %q", cr)
	}
}

func TestLeMediaEstServiEnEntierSansPlage(t *testing.T) {
	s, _ := banc(t)
	id := avecFichier(t, s, "0123456789abcdef")
	w := get(s, "/media/"+itoa(id), membre, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("code %d", w.Code)
	}
	if w.Body.Len() != 16 {
		t.Errorf("%d octets servis sur 16", w.Body.Len())
	}
	if ct := w.Header().Get("Content-Type"); ct != "audio/ogg" {
		t.Errorf("Content-Type = %q", ct)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("le navigateur peut deviner le type d'un fichier venu d'un tiers")
	}
}

// L'AUDIO N'EST PAS PUBLIC : servir les fichiers a qui passe ferait de la board
// un miroir ouvert.
func TestLeMediaNestPasServiAuxInconnus(t *testing.T) {
	s, _ := banc(t)
	id := avecFichier(t, s, "secret")
	if w := get(s, "/media/"+itoa(id), dehors, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("un inconnu obtient l'audio : %d", w.Code)
	}
}

// LE CONFINEMENT DE CHEMIN A DISPARU AVEC SA RAISON D'ETRE.
//
// La radio ne lit plus de fichier : elle relaie le flux de la passerelle. Le
// chemin retenu en base ne sert plus qu'a l'affichage, et ne peut donc plus
// devenir une lecture arbitraire du disque. Le test qui gardait cette
// propriete est retire plutot que laisse a verifier une garde qui n'existe
// plus — un test qui ne peut plus echouer donne une fausse assurance.

func TestUnePisteSansFichierRepondIntrouvable(t *testing.T) {
	s, _ := banc(t)
	p, _, _ := s.st.Ajoute("https://youtu.be/X", "", 1, s.Now())
	if w := get(s, "/media/"+itoa(p.ID), membre, nil); w.Code != http.StatusNotFound {
		t.Errorf("code %d pour une piste sans fichier", w.Code)
	}
}

func TestUneExtensionDecorativeEstAcceptee(t *testing.T) {
	s, _ := banc(t)
	id := avecFichier(t, s, "0123456789abcdef")
	if w := get(s, "/media/"+itoa(id)+".ogg", membre, nil); w.Code != http.StatusOK {
		t.Errorf("/media/<id>.ogg rend %d", w.Code)
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
