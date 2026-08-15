package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// prepare une piste en cache avec un vrai fichier sur disque.
func avecFichier(t *testing.T, s *Serveur, contenu string) int64 {
	t.Helper()
	racine := t.TempDir()
	s.Racine = racine
	chemin := filepath.Join(racine, "piste.ogg")
	if err := os.WriteFile(chemin, []byte(contenu), 0o644); err != nil {
		t.Fatal(err)
	}
	p, _, err := s.st.Ajoute("https://youtu.be/ABC", "T", 1, s.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.st.PoseCache(p.ID, chemin, "audio/ogg", int64(len(contenu)), 180000, "T", "A"); err != nil {
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
func TestLAudioRepondAuxRequetesDePlage(t *testing.T) {
	s, _ := banc(t)
	id := avecFichier(t, s, "0123456789abcdef")

	w := get(s, "/audio/"+itoa(id), membre, map[string]string{"Range": "bytes=4-9"})
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

func TestLAudioEstServiEnEntierSansPlage(t *testing.T) {
	s, _ := banc(t)
	id := avecFichier(t, s, "0123456789abcdef")
	w := get(s, "/audio/"+itoa(id), membre, nil)
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
func TestLAudioNestPasServiAuxInconnus(t *testing.T) {
	s, _ := banc(t)
	id := avecFichier(t, s, "secret")
	if w := get(s, "/audio/"+itoa(id), dehors, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("un inconnu obtient l'audio : %d", w.Code)
	}
}

// ── CONFINEMENT ─────────────────────────────────────────────────────────────
//
// Le chemin vient de la BASE et non de l'adresse — c'est la garde qui compte.
// Le confinement est la seconde barriere : si une ligne portait un jour un
// chemin de travers (import, migration, edition a la main), il ne doit pas
// devenir une lecture arbitraire du disque.
func TestUnCheminHorsDuParcNestPasServi(t *testing.T) {
	s, _ := banc(t)
	racine := t.TempDir()
	s.Racine = racine
	dehorsFic := filepath.Join(t.TempDir(), "ailleurs.txt")
	if err := os.WriteFile(dehorsFic, []byte("hors parc"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, _, _ := s.st.Ajoute("https://youtu.be/X", "", 1, s.Now())
	if err := s.st.PoseCache(p.ID, dehorsFic, "audio/ogg", 9, 1000, "", ""); err != nil {
		t.Fatal(err)
	}
	w := get(s, "/audio/"+itoa(p.ID), membre, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("un fichier hors du parc a ete servi : %d", w.Code)
	}
	if w.Body.String() == "hors parc" {
		t.Error("le contenu hors parc a fuite")
	}
}

func TestUnePisteSansFichierRepondIntrouvable(t *testing.T) {
	s, _ := banc(t)
	p, _, _ := s.st.Ajoute("https://youtu.be/X", "", 1, s.Now())
	if w := get(s, "/audio/"+itoa(p.ID), membre, nil); w.Code != http.StatusNotFound {
		t.Errorf("code %d pour une piste sans fichier", w.Code)
	}
}

func TestUneExtensionDecorativeEstAcceptee(t *testing.T) {
	s, _ := banc(t)
	id := avecFichier(t, s, "0123456789abcdef")
	if w := get(s, "/audio/"+itoa(id)+".ogg", membre, nil); w.Code != http.StatusOK {
		t.Errorf("/audio/<id>.ogg rend %d", w.Code)
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
